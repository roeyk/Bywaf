"""Finding and fact payload mapping for HTTP CORS posture checks.

Provides normalized fact payloads and finding candidates for CORS response
posture observations.

Used by:
- HTTP CORS command orchestration: emit facts and finding candidates.
- tests: verify normalized finding classes and payloads.
"""

from __future__ import annotations

from bywaf.finding import candidate_payload
from bywaf.plugins.http.http_targets import HttpTarget as CorsTarget


def result_payload(
    target: CorsTarget,
    result: dict[str, object],
    origin: str,
    request_method: str,
) -> dict[str, object]:
    """Return the plugin-owned `http.cors` fact payload.

    Called by: `command.run_http_cors()` before yielding the fact.
    """
    # Combine stable target fields, request inputs, raw response headers, and
    # normalized posture booleans in the event schema shape.
    return {
        "url": target.url,
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "path": target.path,
        "origin": origin,
        "request_method": request_method,
        "status": result.get("status"),
        "allow_origin": result.get("allow_origin", ""),
        "allow_credentials": result.get("allow_credentials", ""),
        "allow_methods": result.get("allow_methods", ""),
        "vary": result.get("vary", ""),
        "reflected_origin": bool(result.get("reflected_origin")),
        "wildcard_origin": bool(result.get("wildcard_origin")),
        "credentials_allowed": bool(result.get("credentials_allowed")),
        "error": result.get("error", ""),
    }


def cors_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    """Promote clear unsafe CORS posture into normalized finding candidates.

    Called by: `command.run_http_cors()` after one `http.cors` payload is built.
    """
    findings: list[dict[str, object]] = []
    if payload.get("reflected_origin") and payload.get("credentials_allowed"):
        # Reflected arbitrary origin plus credentials is the clearest high-risk
        # CORS posture in this passive probe.
        findings.append(cors_finding(payload, "web.cors.arbitrary_origin_with_credentials", "CORS reflects arbitrary Origin with credentials", "high"))
    elif payload.get("reflected_origin"):
        # Reflected arbitrary origin without credentials is still usually
        # unsafe, but impact depends more on readable unauthenticated data.
        findings.append(cors_finding(payload, "web.cors.arbitrary_origin_reflected", "CORS reflects arbitrary Origin", "medium"))
    if payload.get("wildcard_origin") and payload.get("credentials_allowed"):
        # The CORS spec rejects wildcard+credentials in browsers, but recording
        # the contradictory posture helps operators fix unsafe server config.
        findings.append(cors_finding(payload, "web.cors.wildcard_with_credentials", "CORS wildcard origin allows credentials", "medium"))
    return findings


def cors_finding(
    payload: dict[str, object],
    finding_class: str,
    title: str,
    severity: str,
) -> dict[str, object]:
    """Return one normalized CORS finding candidate.

    Called by: `cors_findings()` for each detected CORS posture issue.
    """
    # Package the CORS observation into the common finding.candidate contract.
    return candidate_payload(
        title=title,
        finding_class=finding_class,
        severity=severity,
        confidence="medium",
        finding_scope="web_origin",
        target=target_payload(payload),
        identifiers={"cwe": ["CWE-942"], "owasp": ["A05:2021"]},
        affected=[{"url": str(payload["url"])}],
        evidence=(
            f"{payload['url']} responded to Origin {payload['origin']} with "
            f"Access-Control-Allow-Origin: {payload.get('allow_origin') or '<empty>'} "
            f"and Access-Control-Allow-Credentials: {payload.get('allow_credentials') or '<empty>'}."
        ),
        recommendation="Restrict allowed origins to trusted origins and avoid credentialed wildcard or reflection behavior.",
        source={"tool": "http_cors", "topic": "http.cors"},
    )


def target_payload(payload: dict[str, object]) -> dict[str, str]:
    """Return normalized target details for finding candidates.

    Called by: `cors_finding()` when packaging candidate payloads.
    """
    # Finding payloads expect string target fields for stable grouping keys.
    return {
        "scheme": str(payload["scheme"]),
        "host": str(payload["host"]),
        "port": str(payload["port"]),
        "path": str(payload["path"]),
    }


__all__ = [
    "cors_finding",
    "cors_findings",
    "result_payload",
    "target_payload",
]
