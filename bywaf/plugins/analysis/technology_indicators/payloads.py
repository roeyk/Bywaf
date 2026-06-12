"""Payload normalization for passive technology indicator findings.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from bywaf.finding import candidate_payload

from .rules import VersionIndicatorRule


def candidate_for_rule(
    rule: VersionIndicatorRule,
    *,
    payload: dict[str, Any],
    evidence: str,
    source_topic: str,
) -> dict[str, object]:
    """Return a normalized finding candidate for one matching rule.

    Called by: `technology_indicators.findings_from_event()`.
    """
    target = target_from_payload(payload)
    affected = affected_from_target(target)
    observed = observed_snippet(evidence)
    return candidate_payload(
        title=rule.title,
        finding_class=rule.finding_class,
        severity=rule.severity,
        confidence="medium",
        confidence_basis=confidence_for_source_topic(source_topic),
        finding_scope=finding_scope_for_target(target),
        target=target,
        affected=affected,
        identifiers=rule.identifiers,
        evidence=f"{rule.name} matched passive {source_topic} evidence; observed={observed}",
        recommendation=rule.recommendation,
        source={"tool": "technology_indicators", "topic": source_topic},
    )


def evidence_text(payload: dict[str, Any]) -> str:
    """Return normalized passive evidence text from a fact payload.

    Called by: `technology_indicators.findings_from_event()`.
    """
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
    """Return text from web fingerprint observations.

    Called by: `evidence_text()`.
    """
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
    """Return a service or web-origin target from a passive fact payload.

    Called by: `candidate_for_rule()`.
    """
    url = str(payload.get("url") or payload.get("final_url") or "")
    host = str(payload.get("host") or urlparse(url).hostname or "")
    scheme = str(payload.get("scheme") or urlparse(url).scheme or "")
    port = int_value(payload.get("port")) or default_url_port(url)
    protocol = str(payload.get("protocol") or "tcp")
    if scheme in {"http", "https"} or url:
        return {"scheme": scheme or "http", "host": host, "port": str(port or ""), "path": "/"}
    return {"host": host, "port": str(port or ""), "protocol": protocol}


def affected_from_target(target: dict[str, object]) -> list[dict[str, object]]:
    """Return affected resources for a normalized target.

    Called by: `candidate_for_rule()`.
    """
    if "scheme" in target:
        scheme = str(target.get("scheme") or "http")
        host = str(target.get("host") or "")
        port = str(target.get("port") or "")
        return [{"url": f"{scheme}://{host}:{port}/"}]
    return [{"endpoint": f"{target.get('host')}:{target.get('port')}/{target.get('protocol')}"}]


def finding_scope_for_target(target: dict[str, object]) -> str:
    """Return the grouping scope for a target.

    Called by: `candidate_for_rule()`.
    """
    if "scheme" in target:
        return "web_origin"
    return "service"


def confidence_for_source_topic(source_topic: str) -> str:
    """Return why this passive indicator received its confidence label.

    Called by: `candidate_for_rule()`.
    """
    return {
        "service.detected": "version_indicator",
        "tcp.banner": "version_indicator",
        "http.endpoint": "version_indicator",
        "web.fingerprint": "fingerprint_indicator",
    }.get(source_topic, "passive_indicator")


def observed_snippet(evidence: str) -> str:
    """Return compact evidence text for operator-facing findings.

    Called by: `candidate_for_rule()`.
    """
    compact = " ".join(evidence.split())
    if len(compact) <= 160:
        return compact
    return compact[:157] + "..."


def int_value(value: object) -> int | None:
    """Parse an integer field if present.

    Called by: `target_from_payload()`.
    """
    if not isinstance(value, (str, int, float)) or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def default_url_port(url: str) -> int | None:
    """Return the URL port or the scheme default.

    Called by: `target_from_payload()`.
    """
    parsed = urlparse(url)
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None
