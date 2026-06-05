"""Passive technology/version indicator findings.

Promotes existing banner, service, endpoint, and web fingerprint facts into
candidate findings when they match a small curated vulnerable-version table.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, ManifestCommandlet, RunConfig
from bywaf.plugins.analysis.finding_dedupe import dedupe_findings
from bywaf.plugins.analysis.finding_dedupe_normalize import normalize_event
from bywaf.plugins.analysis.finding_dedupe_publish import publish_dedupe_result, summary_line


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
    """Publish deduped indicator candidates from upstream passive facts."""
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


@dataclass(frozen=True, slots=True)
class VersionIndicatorRule:
    """One passive vulnerable-version indicator rule."""

    name: str
    product: str
    versions: tuple[str, ...]
    finding_class: str
    title: str
    severity: str
    identifiers: dict[str, list[str]]
    recommendation: str


RULES = (
    VersionIndicatorRule(
        name="apache-httpd-2.4.49",
        product="apache httpd",
        versions=("2.4.49",),
        finding_class="technology.version.apache_httpd_2_4_49_indicator",
        title="Apache httpd 2.4.49 version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2021-41773"]},
        recommendation=(
            "Confirm the Apache httpd build and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="apache-httpd-2.4.50",
        product="apache httpd",
        versions=("2.4.50",),
        finding_class="technology.version.apache_httpd_2_4_50_indicator",
        title="Apache httpd 2.4.50 version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2021-42013"]},
        recommendation=(
            "Confirm the Apache httpd build and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="nginx-1.3.9-to-1.4.0",
        product="nginx",
        versions=("1.3.9", "1.3.10", "1.3.11", "1.3.12", "1.3.13", "1.3.14", "1.3.15", "1.3.16", "1.4.0"),
        finding_class="technology.version.nginx_1_3_9_to_1_4_0_indicator",
        title="nginx 1.3.9-1.4.0 version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2013-2028"]},
        recommendation=(
            "Confirm the nginx build and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="microsoft-iis-6.0",
        product="microsoft iis",
        versions=("6.0",),
        finding_class="technology.version.microsoft_iis_6_0_indicator",
        title="Microsoft IIS 6.0 version indicator observed",
        severity="critical",
        identifiers={"cve": ["CVE-2017-7269"]},
        recommendation=(
            "Confirm the IIS version, Windows Server release, and WebDAV exposure "
            "with asset owners, then retire or isolate the service if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="openssl-1.0.1-to-1.0.1f",
        product="openssl",
        versions=("1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"),
        finding_class="technology.version.openssl_1_0_1_to_1_0_1f_indicator",
        title="OpenSSL 1.0.1-1.0.1f version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2014-0160"]},
        recommendation=(
            "Confirm the OpenSSL build options and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
)

APACHE_VERSION_RE = re.compile(r"\b(?:apache(?:\s+httpd)?|httpd|apache)/(?P<version>\d+\.\d+\.\d+)\b", re.IGNORECASE)
NGINX_VERSION_RE = re.compile(r"\bnginx/(?P<version>\d+\.\d+\.\d+)\b", re.IGNORECASE)
IIS_VERSION_RE = re.compile(r"\b(?:microsoft-)?iis/(?P<version>\d+\.\d+)\b", re.IGNORECASE)
OPENSSL_VERSION_RE = re.compile(r"\bopenssl/(?P<version>\d+\.\d+\.\d+[a-z]?)\b", re.IGNORECASE)
VERSION_PATTERNS = {
    "apache httpd": APACHE_VERSION_RE,
    "nginx": NGINX_VERSION_RE,
    "microsoft iis": IIS_VERSION_RE,
    "openssl": OPENSSL_VERSION_RE,
}


def findings_from_event(event: Event) -> list[dict[str, object]]:
    """Return candidate findings derived from one upstream fact event."""
    if event.topic not in {"service.detected", "tcp.banner", "http.endpoint", "web.fingerprint"}:
        return []
    payload = dict(event.payload)
    evidence = evidence_text(payload)
    return [candidate_for_rule(rule, payload=payload, evidence=evidence, source_topic=event.topic) for rule in matching_rules(evidence)]


def matching_rules(evidence: str) -> list[VersionIndicatorRule]:
    """Return rules matching passive evidence text."""
    observed_versions = {
        product: {match.group("version").lower() for match in pattern.finditer(evidence)}
        for product, pattern in VERSION_PATTERNS.items()
    }
    return [
        rule
        for rule in RULES
        if any(version.lower() in observed_versions.get(rule.product, set()) for version in rule.versions)
    ]


def candidate_for_rule(
    rule: VersionIndicatorRule,
    *,
    payload: dict[str, Any],
    evidence: str,
    source_topic: str,
) -> dict[str, object]:
    """Return a normalized finding candidate for one matching rule."""
    target = target_from_payload(payload)
    affected = affected_from_target(target)
    observed = observed_snippet(evidence)
    return candidate_payload(
        title=rule.title,
        finding_class=rule.finding_class,
        severity=rule.severity,
        confidence="medium",
        confidence_basis=confidence_basis_for_source_topic(source_topic),
        finding_scope=finding_scope_for_target(target),
        target=target,
        affected=affected,
        identifiers=rule.identifiers,
        evidence=f"{rule.name} matched passive {source_topic} evidence; observed={observed}",
        recommendation=rule.recommendation,
        source={"tool": "technology_indicators", "topic": source_topic},
    )


def evidence_text(payload: dict[str, Any]) -> str:
    """Return normalized passive evidence text from a fact payload."""
    observations = payload.get("observations")
    technologies = payload.get("technologies")
    parts = [
        payload.get("service"),
        payload.get("banner"),
        payload.get("evidence"),
        payload.get("server"),
        payload.get("title"),
        payload.get("content_type"),
        " ".join(str(item) for item in technologies) if isinstance(technologies, list) else technologies,
        observation_text(observations),
    ]
    return " ".join(str(part) for part in parts if part)


def observation_text(observations: object) -> str:
    """Return text from web fingerprint observations."""
    if not isinstance(observations, list):
        return str(observations or "")
    parts: list[str] = []
    for item in observations:
        if isinstance(item, dict):
            parts.extend(str(value) for value in item.values() if value)
        elif item:
            parts.append(str(item))
    return " ".join(parts)


def target_from_payload(payload: dict[str, Any]) -> dict[str, object]:
    """Return a service or web-origin target from a passive fact payload."""
    url = str(payload.get("url") or payload.get("final_url") or "")
    host = str(payload.get("host") or urlparse(url).hostname or "")
    scheme = str(payload.get("scheme") or urlparse(url).scheme or "")
    port = int_value(payload.get("port")) or default_url_port(url)
    protocol = str(payload.get("protocol") or "tcp")
    if scheme in {"http", "https"} or url:
        return {"scheme": scheme or "http", "host": host, "port": str(port or ""), "path": "/"}
    return {"host": host, "port": str(port or ""), "protocol": protocol}


def affected_from_target(target: dict[str, object]) -> list[dict[str, object]]:
    """Return affected resources for a normalized target."""
    if "scheme" in target:
        scheme = str(target.get("scheme") or "http")
        host = str(target.get("host") or "")
        port = str(target.get("port") or "")
        return [{"url": f"{scheme}://{host}:{port}/"}]
    return [{"endpoint": f"{target.get('host')}:{target.get('port')}/{target.get('protocol')}"}]


def finding_scope_for_target(target: dict[str, object]) -> str:
    """Return the grouping scope for a target."""
    if "scheme" in target:
        return "web_origin"
    return "service"


def confidence_basis_for_source_topic(source_topic: str) -> str:
    """Return why this passive indicator received its confidence label."""
    return {
        "service.detected": "version_indicator",
        "tcp.banner": "version_indicator",
        "http.endpoint": "version_indicator",
        "web.fingerprint": "fingerprint_indicator",
    }.get(source_topic, "passive_indicator")


def observed_snippet(evidence: str) -> str:
    """Return compact evidence text for operator-facing findings."""
    compact = " ".join(evidence.split())
    if len(compact) <= 160:
        return compact
    return compact[:157] + "..."


def int_value(value: object) -> int | None:
    """Parse an integer field if present."""
    if not isinstance(value, (str, int, float)) or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def default_url_port(url: str) -> int | None:
    """Return the URL port or the scheme default."""
    parsed = urlparse(url)
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return technology_indicators


def plugins() -> tuple[Commandlet, ...]:
    """Return technology indicator commandlets."""
    return technology_indicators, tech_review


technology_indicators = TechnologyIndicators()
tech_review = TechReview()
