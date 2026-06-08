"""Finding packaging for HTTP header checks.

Provides normalized result payloads and finding candidates for missing
high-value HTTP security headers.

Used by:
- HTTP header command orchestration: emit facts and finding candidates.
- finding helper facade: expose compatibility helpers during transition."""

from __future__ import annotations

from bywaf.finding import candidate_payload

from .models import HeaderProbeResult


def missing_security_header_candidates(result: HeaderProbeResult) -> list[dict[str, object]]:
    """Return finding candidates for missing high-value HTTP security headers."""
    headers = {str(key).lower(): value for key, value in result.headers.items()}
    target = result.target
    scheme = "https" if target.use_ssl else "http"
    candidates: list[dict[str, object]] = []
    url = f"{scheme}://{target.host}:{target.port}/"
    # Transport/content-sniffing headers are direct per-origin checks from the
    # observed response header dictionary.
    if target.use_ssl and "strict-transport-security" not in headers:
        # HSTS is scoped to the web origin rather than a single route. Multiple
        # pages on the same scheme/host/port should group into one report item.
        candidates.append(
            candidate_payload(
                title="Missing HTTP Strict Transport Security",
                finding_class="web.header.missing_hsts",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={"cwe": ["CWE-319"]},
                affected=[{"url": url}],
                evidence=f"{url} did not return Strict-Transport-Security.",
                recommendation="Enable HSTS for HTTPS services after confirming all subdomains support TLS.",
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    if "x-content-type-options" not in headers:
        # X-Content-Type-Options is also origin-level for this simple probe. A
        # route-specific plugin can choose `finding_scope="web_route"` instead.
        candidates.append(
            candidate_payload(
                title="Missing X-Content-Type-Options",
                finding_class="web.header.missing_x_content_type_options",
                severity="low",
                confidence="medium",
                finding_scope="web_origin",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={},
                affected=[{"url": url}],
                evidence=f"{url} did not return X-Content-Type-Options.",
                recommendation='Set X-Content-Type-Options to "nosniff" for HTTP responses.',
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    if missing_framing_policy(headers):
        # Framing protection can be provided by either legacy X-Frame-Options or
        # CSP frame-ancestors, so it uses a helper instead of one header lookup.
        candidates.append(
            candidate_payload(
                title="Missing browser framing protection",
                finding_class="web.header.missing_framing_policy",
                severity="low",
                confidence="medium",
                finding_scope="web_origin",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={"cwe": ["CWE-1021"], "owasp": ["A05:2021"]},
                affected=[{"url": url}],
                evidence=f"{url} did not return X-Frame-Options or a Content-Security-Policy frame-ancestors directive.",
                recommendation="Set Content-Security-Policy frame-ancestors, or X-Frame-Options for legacy browser coverage.",
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    if "content-security-policy" not in headers:
        candidates.append(
            candidate_payload(
                title="Missing Content-Security-Policy",
                finding_class="web.header.missing_content_security_policy",
                severity="low",
                confidence="medium",
                finding_scope="web_origin",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={"cwe": ["CWE-693"], "owasp": ["A05:2021"]},
                affected=[{"url": url}],
                evidence=f"{url} did not return Content-Security-Policy.",
                recommendation="Set a Content-Security-Policy that restricts script, object, frame, and other high-risk content sources.",
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    if "referrer-policy" not in headers:
        candidates.append(
            candidate_payload(
                title="Missing Referrer-Policy",
                finding_class="web.header.missing_referrer_policy",
                severity="info",
                confidence="medium",
                finding_scope="web_origin",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={},
                affected=[{"url": url}],
                evidence=f"{url} did not return Referrer-Policy.",
                recommendation='Set Referrer-Policy to a deliberate value such as "strict-origin-when-cross-origin" or stricter.',
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    cookie_findings = weak_cookie_candidates(headers, url, scheme, target.host, target.port)
    candidates.extend(cookie_findings)
    # Disclosure and redirect checks are lower-confidence informational signals,
    # appended after the missing-header findings so report output groups the
    # primary security-header gaps first.
    if server := exposed_server_header(headers):
        candidates.append(
            candidate_payload(
                title="HTTP Server header exposes implementation details",
                finding_class="web.header.server_disclosure",
                severity="info",
                confidence="medium",
                finding_scope="web_origin",
                target={"scheme": scheme, "host": target.host, "port": str(target.port), "path": "/"},
                identifiers={},
                affected=[{"url": url}],
                evidence=f"{url} returned Server: {server}.",
                recommendation="Review whether the Server header reveals unnecessary product or version information.",
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        )
    if redirect := headers.get("location"):
        candidates.extend(redirect_candidates(redirect, url, scheme, target.host, target.port))
    return candidates


def weak_cookie_candidates(
    headers: dict[str, str],
    url: str,
    scheme: str,
    host: str,
    port: int,
) -> list[dict[str, object]]:
    """Return candidates for cookies missing common security attributes."""
    raw_cookie = headers.get("set-cookie", "")
    if not raw_cookie:
        return []
    lower_cookie = raw_cookie.casefold()
    missing: list[tuple[str, str, str]] = []
    if scheme == "https" and "secure" not in cookie_attribute_tokens(lower_cookie):
        missing.append(("Secure", "web.cookie.missing_secure", "Set Secure on cookies delivered over HTTPS."))
    if "httponly" not in cookie_attribute_tokens(lower_cookie):
        missing.append(("HttpOnly", "web.cookie.missing_httponly", "Set HttpOnly on session cookies that do not need JavaScript access."))
    if "samesite" not in lower_cookie:
        missing.append(("SameSite", "web.cookie.missing_samesite", "Set an explicit SameSite attribute for browser cookies."))
    return [
        candidate_payload(
            title=f"HTTP cookie missing {attribute}",
            finding_class=finding_class,
            severity="low",
            confidence="medium",
            finding_scope="web_origin",
            target={"scheme": scheme, "host": host, "port": str(port), "path": "/"},
            identifiers={},
            affected=[{"url": url}],
            evidence=f"{url} returned a Set-Cookie header without {attribute}: {raw_cookie}",
            recommendation=recommendation,
            source={"tool": "http_headers", "topic": "http.headers"},
        )
        for attribute, finding_class, recommendation in missing
    ]


def cookie_attribute_tokens(raw_cookie: str) -> set[str]:
    """Return normalized Set-Cookie attribute tokens."""
    return {part.strip().split("=", 1)[0].casefold() for part in raw_cookie.split(";") if part.strip()}


def missing_framing_policy(headers: dict[str, str]) -> bool:
    """Return whether headers lack common browser framing controls."""
    if "x-frame-options" in headers:
        return False
    return "frame-ancestors" not in str(headers.get("content-security-policy") or "").casefold()


def exposed_server_header(headers: dict[str, str]) -> str:
    """Return a server header value that looks implementation-specific."""
    server = str(headers.get("server") or "").strip()
    if not server:
        return ""
    if any(char.isdigit() for char in server) or "/" in server:
        return server
    return ""


def redirect_candidates(
    location: str,
    url: str,
    scheme: str,
    host: str,
    port: int,
) -> list[dict[str, object]]:
    """Return candidates for interesting redirect behavior."""
    if not location.strip():
        return []
    lowered = location.casefold()
    if scheme == "https" and lowered.startswith("http://"):
        return [
            candidate_payload(
                title="HTTPS endpoint redirects to plaintext HTTP",
                finding_class="web.redirect.https_to_http",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target={"scheme": scheme, "host": host, "port": str(port), "path": "/"},
                identifiers={"cwe": ["CWE-319"]},
                affected=[{"url": url}],
                evidence=f"{url} redirects to {location}.",
                recommendation="Keep HTTPS users on HTTPS targets during redirects.",
                source={"tool": "http_headers", "topic": "http.headers"},
            )
        ]
    return []


def result_payload(result: HeaderProbeResult) -> dict[str, object]:
    """Return the fact payload for one HTTP header probe."""
    return {
        "host": result.target.host,
        "port": result.target.port,
        "status": result.status,
        "headers": result.headers,
    }
