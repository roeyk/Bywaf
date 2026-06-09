"""Management service exposure detector.

Promotes existing service, port, banner, and web fingerprint facts into
candidate findings when they indicate exposed administrative surfaces.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast
from urllib.parse import urlparse

from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet
from bywaf.plugins.network.management_rules import ExposureRule, matching_rules


@commandlet
def management_exposure(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Emit candidate findings for exposed management services."""
    cfg = cast(ManagementExposureConfig, cfg)
    seen: set[tuple[str, str, str]] = set()
    for event in input_events:
        for finding in findings_from_event(event):
            marker = (str(finding["class"]), str(finding["finding_scope"]), str(finding["target"]))
            if marker in seen:
                continue
            seen.add(marker)
            context.events.publish("finding.candidate", finding)
            context.alert(str(finding["title"]), level="finding", silent=cfg.silent)
    return ()


class ManagementExposureConfig(RunConfig):
    """Typed effective config for management_exposure."""

    silent: bool


def findings_from_event(event: Event) -> list[dict[str, object]]:
    """Return candidate findings derived from one upstream fact event."""
    if event.topic in {"port.open", "service.detected", "tcp.banner"}:
        return service_findings(event)
    if event.topic in {"http.endpoint", "web.fingerprint"}:
        return web_findings(event)
    return []


def service_findings(event: Event) -> list[dict[str, object]]:
    """Return findings from service, port, or banner facts."""
    payload = dict(event.payload)
    host = str(payload.get("host") or "")
    port = int_value(payload.get("port"))
    protocol = str(payload.get("protocol") or "tcp")
    evidence = service_evidence(payload)
    if not host or port is None:
        return []
    matches = matching_rules(port, evidence)
    return [
        exposure_candidate(rule, host=host, port=port, protocol=protocol, evidence=evidence, source_topic=event.topic)
        for rule in matches
    ]


def web_findings(event: Event) -> list[dict[str, object]]:
    """Return findings from HTTP endpoint and web fingerprint facts."""
    payload = dict(event.payload)
    url = str(payload.get("url") or payload.get("final_url") or "")
    host = str(payload.get("host") or urlparse(url).hostname or "")
    port = int_value(payload.get("port")) or default_url_port(url)
    scheme = str(payload.get("scheme") or urlparse(url).scheme or "http")
    evidence = web_evidence(payload)
    if not host or port is None:
        return []
    return [
        web_exposure_candidate(rule, scheme=scheme, host=host, port=port, url=url, evidence=evidence, source_topic=event.topic)
        for rule in matching_rules(port, evidence)
    ]


def service_evidence(payload: dict[str, Any]) -> str:
    """Return normalized service evidence text from a fact payload."""
    parts = [
        payload.get("service"),
        payload.get("banner"),
        payload.get("evidence"),
        payload.get("error"),
    ]
    return " ".join(str(part) for part in parts if part)


def web_evidence(payload: dict[str, Any]) -> str:
    """Return normalized web evidence text from a fact payload."""
    observations = payload.get("observations")
    technologies = payload.get("technologies")
    parts = [
        payload.get("title"),
        payload.get("server"),
        payload.get("content_type"),
        payload.get("url"),
        payload.get("final_url"),
        " ".join(str(item) for item in technologies) if isinstance(technologies, list) else technologies,
        " ".join(str(item) for item in observations) if isinstance(observations, list) else observations,
    ]
    return " ".join(str(part) for part in parts if part)


def exposure_candidate(
    rule: ExposureRule,
    *,
    host: str,
    port: int,
    protocol: str,
    evidence: str,
    source_topic: str,
) -> dict[str, object]:
    """Return a service-scope exposure finding candidate."""
    endpoint = f"{host}:{port}/{protocol}"
    finding_evidence = service_finding_evidence(rule, endpoint=endpoint, source_topic=source_topic, evidence=evidence)
    return candidate_payload(
        title=rule.title,
        finding_class=rule.finding_class,
        severity=rule.severity,
        confidence="medium",
        confidence_basis=confidence_basis_for_source_topic(source_topic),
        finding_scope="service",
        target={"host": host, "port": str(port), "protocol": protocol},
        affected=[{"endpoint": endpoint}],
        evidence=finding_evidence,
        recommendation=rule.recommendation,
        source={"tool": "management_exposure", "topic": source_topic},
    )


def web_exposure_candidate(
    rule: ExposureRule,
    *,
    scheme: str,
    host: str,
    port: int,
    url: str,
    evidence: str,
    source_topic: str,
) -> dict[str, object]:
    """Return a web-origin exposure finding candidate."""
    display_url = url or f"{scheme}://{host}:{port}/"
    finding_evidence = web_finding_evidence(rule, url=display_url, source_topic=source_topic, evidence=evidence)
    return candidate_payload(
        title=rule.title,
        finding_class=rule.finding_class,
        severity=rule.severity,
        confidence="medium",
        confidence_basis=confidence_basis_for_source_topic(source_topic),
        finding_scope="web_origin",
        target={"scheme": scheme, "host": host, "port": str(port), "path": "/"},
        affected=[{"url": display_url}],
        evidence=finding_evidence,
        recommendation=rule.recommendation,
        source={"tool": "management_exposure", "topic": source_topic},
    )


def service_finding_evidence(rule: ExposureRule, *, endpoint: str, source_topic: str, evidence: str) -> str:
    """Return operator-facing evidence for one service exposure finding."""
    details = [f"{endpoint} matched {rule.name} management exposure rule", f"source={source_topic}"]
    if evidence:
        details.append(f"observed={evidence}")
    return "; ".join(details)


def web_finding_evidence(rule: ExposureRule, *, url: str, source_topic: str, evidence: str) -> str:
    """Return operator-facing evidence for one web exposure finding."""
    details = [f"{url} matched {rule.name} management exposure rule", f"source={source_topic}"]
    if evidence:
        details.append(f"observed={evidence}")
    return "; ".join(details)


def confidence_basis_for_source_topic(source_topic: str) -> str:
    """Return why a passive exposure finding received its confidence label."""
    return {
        "port.open": "port_indicator",
        "service.detected": "service_indicator",
        "tcp.banner": "banner_indicator",
        "http.endpoint": "endpoint_indicator",
        "web.fingerprint": "fingerprint_indicator",
    }.get(source_topic, "passive_indicator")


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
    return management_exposure
