"""Finding packaging for HTTP header checks.

Provides normalized result payloads and finding candidates for missing
high-value HTTP security headers.

Used by:
- HTTP header command orchestration: emit facts and finding candidates.
- finding helper facade: expose compatibility helpers during transition."""

from __future__ import annotations

from bywaf.finding import candidate_payload

from .models import HeaderProbeResult


def missing_sec_headers(result: HeaderProbeResult) -> list[dict[str, object]]:
    """Return finding candidates for missing high-value HTTP security headers.

    Called by: `command.run_http_headers()` after one header probe succeeds.
    """
    # Normalize header names to lowercase so each check can use one spelling
    # regardless of server capitalization.
    headers = {str(key).lower(): value for key, value in result.headers.items()}
    target = result.target

    # Reconstruct the probed origin from the target model for finding scope,
    # affected URL, and evidence text.
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
        # CSP is broad browser-side hardening. This simple check only records
        # absence; policy quality belongs in a deeper CSP-specific analyzer.
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
        # Referrer-Policy is informational here because impact depends on
        # application routes and cross-origin data exposure.
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
    # Append cookie attribute findings generated from Set-Cookie, if present.
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
        # Inspect redirect targets after disclosure checks; redirects are
        # optional response behavior rather than required security headers.
        candidates.extend(redirect_candidates(redirect, url, scheme, target.host, target.port))
    return candidates


def weak_cookie_candidates(
    headers: dict[str, str],
    url: str,
    scheme: str,
    host: str,
    port: int,
) -> list[dict[str, object]]:
    """Return candidates for cookies missing common security attributes.

    Called by: `missing_sec_headers()` when Set-Cookie exists.
    """
    raw_cookie = headers.get("set-cookie", "")
    if not raw_cookie:
        return []

    # Casefold the whole cookie string for substring checks such as SameSite.
    lower_cookie = raw_cookie.casefold()
    missing: list[tuple[str, str, str]] = []

    # Tokenized attribute checks avoid treating cookie values that merely
    # contain words like "secure" as actual attributes.
    if scheme == "https" and "secure" not in cookie_attribute_tokens(lower_cookie):
        missing.append(("Secure", "web.cookie.missing_secure", "Set Secure on cookies delivered over HTTPS."))
    if "httponly" not in cookie_attribute_tokens(lower_cookie):
        missing.append(("HttpOnly", "web.cookie.missing_httponly", "Set HttpOnly on session cookies that do not need JavaScript access."))
    if "samesite" not in lower_cookie:
        missing.append(("SameSite", "web.cookie.missing_samesite", "Set an explicit SameSite attribute for browser cookies."))

    # Convert each missing attribute tuple into a standard finding candidate.
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
    """Return normalized Set-Cookie attribute tokens.

    Called by: `weak_cookie_candidates()` for exact cookie-attribute checks.
    """
    # Split a Set-Cookie header into semicolon-delimited parts and keep the
    # attribute name before any optional `=value`.
    return {part.strip().split("=", 1)[0].casefold() for part in raw_cookie.split(";") if part.strip()}


def missing_framing_policy(headers: dict[str, str]) -> bool:
    """Return whether headers lack common browser framing controls.

    Called by: `missing_sec_headers()`.
    """
    if "x-frame-options" in headers:
        return False

    # CSP frame-ancestors is the modern equivalent framing control.
    return "frame-ancestors" not in str(headers.get("content-security-policy") or "").casefold()


def exposed_server_header(headers: dict[str, str]) -> str:
    """Return a server header value that looks implementation-specific.

    Called by: `missing_sec_headers()`.
    """
    server = str(headers.get("server") or "").strip()
    if not server:
        return ""

    # Version-like digits or product separators are the main disclosure signal.
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
    """Return candidates for interesting redirect behavior.

    Called by: `missing_sec_headers()` when Location is present.
    """
    if not location.strip():
        return []

    # Normalize only for scheme comparison; preserve the original redirect
    # value in evidence.
    lowered = location.casefold()
    if scheme == "https" and lowered.startswith("http://"):
        # HTTPS-to-HTTP redirects downgrade the user's transport security.
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
    """Return the fact payload for one HTTP header probe.

    Called by: `command.run_http_headers()` before yielding `http.headers`.
    """
    # Convert the internal result model into the plugin-owned event schema.
    return {
        "host": result.target.host,
        "port": result.target.port,
        "status": result.status,
        "headers": result.headers,
    }
