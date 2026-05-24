"""Finding packaging for HTTP header checks."""

from __future__ import annotations

from bywaf.findings import candidate_payload

from .http_headers_models import HeaderProbeResult


def missing_security_header_candidates(result: HeaderProbeResult) -> list[dict[str, object]]:
    """Return finding candidates for missing high-value HTTP security headers."""
    headers = {str(key).lower(): value for key, value in result.headers.items()}
    target = result.target
    scheme = "https" if target.use_ssl else "http"
    candidates: list[dict[str, object]] = []
    if target.use_ssl and "strict-transport-security" not in headers:
        candidates.append(
            candidate_payload(
                title="Missing HTTP Strict Transport Security",
                finding_class="missing-hsts",
                severity="medium",
                confidence="medium",
                finding_scope="application",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={"cwe": ["CWE-319"]},
                affected=[{"url": f"{scheme}://{target.host}:{target.port}/"}],
                evidence=f"{scheme}://{target.host}:{target.port}/ did not return Strict-Transport-Security.",
                recommendation="Enable HSTS for HTTPS services after confirming all subdomains support TLS.",
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    if "x-content-type-options" not in headers:
        candidates.append(
            candidate_payload(
                title="Missing X-Content-Type-Options",
                finding_class="missing-x-content-type-options",
                severity="low",
                confidence="medium",
                finding_scope="application",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={},
                affected=[{"url": f"{scheme}://{target.host}:{target.port}/"}],
                evidence=f"{scheme}://{target.host}:{target.port}/ did not return X-Content-Type-Options.",
                recommendation='Set X-Content-Type-Options to "nosniff" for HTTP responses.',
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    return candidates


def result_payload(result: HeaderProbeResult) -> dict[str, object]:
    """Return the fact payload for one HTTP header probe."""
    return {
        "host": result.target.host,
        "port": result.target.port,
        "status": result.status,
        "headers": result.headers,
    }
