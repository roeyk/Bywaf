"""Finding and fact payload mapping for HTTP authentication checks.

Provides normalized fact payloads and finding candidates for HTTP
authentication challenge observations.

Used by:
- HTTP auth command orchestration: emit facts and finding candidates.
- tests: verify normalized finding classes and payloads.
"""

from __future__ import annotations

from bywaf.finding import candidate_payload
from bywaf.plugins.http.http_targets import HttpTarget as AuthTarget

# Administrative/login path hints used for passive exposure findings.
#
# Used by: `is_adminish_path()`, which keeps the path classification data out
# of the finding-generation branches.
ADMIN_PATH_HINTS = ("/admin", "/login", "/manager", "/console", "/dashboard", "/wp-admin")


def result_payload(target: AuthTarget, result: dict[str, object], method: str) -> dict[str, object]:
    """Return the plugin-owned `http.auth` fact payload.

    Called by: `command.run_http_auth()` before yielding the fact.
    """
    schemes = result.get("schemes", [])
    # Combine stable target fields with probe response fields in the event
    # schema shape declared by the plugin manifest.
    return {
        "url": target.url,
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "path": target.path,
        "method": method,
        "status": result.get("status"),
        "auth_present": bool(schemes),
        "schemes": schemes,
        "realms": result.get("realms", []),
        "www_authenticate": result.get("www_authenticate", []),
        "proxy_authenticate": result.get("proxy_authenticate", []),
        "error": result.get("error", ""),
    }


def auth_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    """Promote auth challenge posture into normalized finding candidates.

    Called by: `command.run_http_auth()` after one `http.auth` payload is
    built.
    """
    # Accept a loose payload because this helper may also be used by analysis
    # or tests reading persisted event dictionaries.
    schemes = schemes_from_payload(payload)
    findings: list[dict[str, object]] = []
    if "BASIC" in schemes and payload.get("scheme") == "http":
        # Basic over plaintext HTTP exposes credentials to transport observers.
        findings.append(
            candidate_payload(
                title="HTTP Basic authentication offered without TLS",
                finding_class="web.auth.basic_over_cleartext",
                severity="medium",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-319"], "owasp": ["A02:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} advertised Basic authentication over HTTP.",
                recommendation="Require HTTPS before Basic authentication is offered or accepted.",
                source={"tool": "http_auth", "topic": "http.auth"},
            )
        )
    if payload.get("auth_present") and is_adminish_path(str(payload.get("path", ""))):
        # An auth challenge on an administrative-looking path is not
        # necessarily vulnerable, but it is useful exposure evidence.
        findings.append(
            candidate_payload(
                title="Authentication challenge observed on administrative-looking path",
                finding_class="web.auth.admin_challenge_observed",
                severity="info",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_route",
                target=target_payload(payload),
                identifiers={"owasp": ["A01:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} returned authentication challenge schemes: {', '.join(schemes)}.",
                recommendation="Review whether this administrative-looking endpoint is expected to be exposed in scope.",
                source={"tool": "http_auth", "topic": "http.auth"},
            )
        )
    if "BASIC" in schemes and not realms_from_payload(payload):
        # Missing realms make protected areas harder for operators/users to
        # distinguish and are a low-severity posture issue.
        findings.append(
            candidate_payload(
                title="HTTP Basic authentication challenge has no realm",
                finding_class="web.auth.basic_missing_realm",
                severity="low",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-16"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} advertised Basic authentication without a realm value.",
                recommendation="Set a non-sensitive authentication realm so operators can distinguish protected areas.",
                source={"tool": "http_auth", "topic": "http.auth"},
            )
        )
    return findings


def schemes_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Return normalized scheme names from a loose event payload.

    Called by: `auth_findings()` for persisted or freshly built payloads.
    """
    value = payload.get("schemes", ())
    if not isinstance(value, list | tuple):
        return ()

    # Convert stored values back to uppercase scheme names for matching.
    return tuple(str(scheme).upper() for scheme in value if scheme)


def realms_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Return realm values from a loose event payload.

    Called by: `auth_findings()` when checking Basic challenge posture.
    """
    value = payload.get("realms", ())
    if not isinstance(value, list | tuple):
        return ()

    # Keep realm text as strings while tolerating loose persisted payloads.
    return tuple(str(realm) for realm in value if realm)


def is_adminish_path(path: str) -> bool:
    """Return whether a path looks like an administrative or login surface.

    Called by: `auth_findings()` for exposure-style posture findings.
    """
    # Normalize the path before comparing against known administrative hints.
    normalized = path.lower()
    return any(normalized == hint or normalized.startswith(f"{hint}/") for hint in ADMIN_PATH_HINTS)


def target_payload(payload: dict[str, object]) -> dict[str, str]:
    """Return normalized target details for finding candidates.

    Called by: `auth_findings()` when packaging candidate payloads.
    """
    # Finding payloads expect string target fields for stable grouping keys.
    return {
        "scheme": str(payload["scheme"]),
        "host": str(payload["host"]),
        "port": str(payload["port"]),
        "path": str(payload["path"]),
    }


__all__ = [
    "ADMIN_PATH_HINTS",
    "auth_findings",
    "is_adminish_path",
    "realms_from_payload",
    "result_payload",
    "schemes_from_payload",
    "target_payload",
]
