"""Finding candidate helpers.

Provides small constructors for normalized finding-candidate payloads so
plugins do not invent incompatible finding shapes.

Used by:
- bundled commandlets: promote selected fact events into reviewable finding
  candidates.
- analysis commandlets: normalize and report candidate payloads."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def candidate_payload(
    *,
    title: str,
    finding_class: str,
    target: dict[str, Any],
    severity: str = "info",
    confidence: str = "medium",
    evidence: str = "",
    recommendation: str = "",
    identifiers: dict[str, list[str]] | None = None,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a normalized finding candidate payload."""
    payload = {
        "status": "potential",
        "confidence": confidence,
        "severity": severity,
        "class": finding_class,
        "title": title,
        "target": compact(target),
        "identifiers": identifiers or {},
        "evidence": evidence,
        "recommendation": recommendation,
        "sources": [compact(source or {})],
    }
    payload["finding_id"] = stable_finding_id(payload)
    return compact(payload)


def telnet_open_candidate(port_payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return a finding candidate for an exposed Telnet service."""
    port = str(port_payload.get("port") or "")
    service = str(port_payload.get("service") or "").lower()
    service_detected = service == "telnet"
    default_port_heuristic = port == "23"
    if not service_detected and not default_port_heuristic:
        return None
    host = str(port_payload.get("host") or "")
    protocol = str(port_payload.get("protocol") or "tcp")
    if service_detected:
        confidence = "high"
        evidence = f"{host}:{port}/{protocol} was identified as Telnet."
    else:
        confidence = "medium"
        evidence = f"{host}:{port}/{protocol} is open on the default Telnet port; confirm service identity."
    return candidate_payload(
        title="Telnet service exposed",
        finding_class="insecure-cleartext-management",
        severity="medium",
        confidence=confidence,
        target={"host": host, "port": port, "protocol": protocol, "service": service or "telnet"},
        evidence=evidence,
        recommendation="Disable Telnet or replace it with SSH or another encrypted management channel.",
        source={"tool": port_payload.get("scanner") or "portscanner", "topic": "port.open"},
    )


def missing_http_security_header_candidates(headers_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return finding candidates for missing high-value HTTP security headers."""
    headers = {str(key).lower(): value for key, value in dict(headers_payload.get("headers") or {}).items()}
    host = str(headers_payload.get("host") or "")
    port = str(headers_payload.get("port") or "")
    use_tls = port == "443"
    candidates: list[dict[str, Any]] = []
    if use_tls and "strict-transport-security" not in headers:
        candidates.append(
            candidate_payload(
                title="Missing HTTP Strict Transport Security",
                finding_class="missing-hsts",
                severity="medium",
                confidence="medium",
                target={"scheme": "https", "host": host, "port": port, "path": "/"},
                evidence=f"https://{host}:{port}/ did not return Strict-Transport-Security.",
                recommendation="Enable HSTS for HTTPS services after confirming all subdomains support TLS.",
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    if "x-content-type-options" not in headers:
        scheme = "https" if use_tls else "http"
        candidates.append(
            candidate_payload(
                title="Missing X-Content-Type-Options",
                finding_class="missing-x-content-type-options",
                severity="low",
                confidence="medium",
                target={"scheme": scheme, "host": host, "port": port, "path": "/"},
                evidence=f"{scheme}://{host}:{port}/ did not return X-Content-Type-Options.",
                recommendation='Set X-Content-Type-Options to "nosniff" for HTTP responses.',
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    return candidates


def stable_finding_id(payload: dict[str, Any]) -> str:
    """Return a deterministic id for one candidate payload."""
    basis = {
        "class": payload.get("class"),
        "identifiers": payload.get("identifiers"),
        "target": payload.get("target"),
        "title": payload.get("title"),
    }
    encoded = json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "finding-" + hashlib.sha256(encoded).hexdigest()[:24]


def compact(payload: dict[str, Any]) -> dict[str, Any]:
    """Return payload with empty values removed recursively."""
    compacted: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = compact(value)
            if nested:
                compacted[key] = nested
        elif isinstance(value, list):
            values = [item for item in value if item not in ("", None, {}, [])]
            if values:
                compacted[key] = values
        elif value not in ("", None):
            compacted[key] = value
    return compacted
