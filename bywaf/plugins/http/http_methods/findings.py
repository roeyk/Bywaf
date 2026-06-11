"""Finding and fact payload mapping for HTTP method checks.

Provides normalized fact payloads and finding candidates for HTTP OPTIONS
observations.

Used by:
- HTTP methods command orchestration: emit facts and finding candidates.
- tests: verify normalized finding classes and payloads.
"""

from __future__ import annotations

from bywaf.finding import candidate_payload
from bywaf.plugins.http.http_targets import HttpTarget as MethodTarget

# Classification tables for method-risk promotion.
#
# Used by: `method_findings()`, which treats write-capable methods and WebDAV
# methods as separate finding classes even though their operational risk can
# overlap.
WRITE_METHODS = ("PUT", "PATCH", "DELETE")
WEBDAV_METHODS = ("PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")


def result_payload(target: MethodTarget, result: dict[str, object]) -> dict[str, object]:
    """Return the plugin-owned `http.methods` fact payload.

    Called by: `command.run_http_methods()` before yielding the fact.
    """
    # Combine stable target fields with probe response fields in the event
    # schema shape declared by the plugin manifest.
    return {
        "url": target.url,
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "path": target.path,
        "status": result.get("status"),
        "methods": result.get("methods", []),
        "allow": result.get("allow", ""),
        "public": result.get("public", ""),
        "error": result.get("error", ""),
    }


def method_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    """Promote risky allowed methods into normalized finding candidates.

    Called by: `command.run_http_methods()` after one `http.methods` payload is
    built.
    """
    # Accept a loose payload because this helper may also be used by analysis
    # or tests reading persisted event dictionaries.
    methods = methods_from_payload(payload)
    findings: list[dict[str, object]] = []
    if "TRACE" in methods:
        # TRACE is a distinct browser/proxy risk and gets its own finding even
        # when other risky methods are also present.
        findings.append(
            candidate_payload(
                title="HTTP TRACE method enabled",
                finding_class="web.method.trace_enabled",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-16"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed HTTP methods: {', '.join(methods)}.",
                recommendation="Disable TRACE unless there is a documented operational requirement.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    write_methods = [method for method in WRITE_METHODS if method in methods]
    if write_methods:
        # PUT/PATCH/DELETE imply write-capable behavior and should be grouped
        # separately from TRACE and WebDAV findings.
        findings.append(
            candidate_payload(
                title="HTTP write-capable methods enabled",
                finding_class="web.method.write_methods_enabled",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-650"], "owasp": ["A01:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed write-capable HTTP methods: {', '.join(write_methods)}.",
                recommendation="Disable PUT, PATCH, and DELETE unless they are required and access-controlled.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    webdav_methods = [method for method in WEBDAV_METHODS if method in methods]
    if webdav_methods:
        # WebDAV methods often imply additional server-side file operation
        # surface, so they remain a distinct finding class.
        findings.append(
            candidate_payload(
                title="WebDAV HTTP methods enabled",
                finding_class="web.method.webdav_enabled",
                severity="medium",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-650"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed WebDAV HTTP methods: {', '.join(webdav_methods)}.",
                recommendation="Disable WebDAV methods unless they are required and access-controlled.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    return findings


def methods_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Return normalized method names from a loose event payload.

    Called by: `command.run_http_methods()` and `method_findings()`.
    """
    value = payload.get("methods", ())
    if not isinstance(value, list | tuple):
        return ()

    # Convert stored values back to uppercase method names for matching and
    # display, tolerating loose persisted payloads.
    return tuple(str(method).upper() for method in value if method)


def target_payload(payload: dict[str, object]) -> dict[str, str]:
    """Return normalized target details for finding candidates.

    Called by: `method_findings()` when packaging candidate payloads.
    """
    # Finding payloads expect string target fields for stable grouping keys.
    return {
        "scheme": str(payload["scheme"]),
        "host": str(payload["host"]),
        "port": str(payload["port"]),
        "path": str(payload["path"]),
    }


__all__ = [
    "WEBDAV_METHODS",
    "WRITE_METHODS",
    "method_findings",
    "methods_from_payload",
    "result_payload",
    "target_payload",
]
