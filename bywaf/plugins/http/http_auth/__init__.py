"""HTTP authentication challenge posture commandlet."""

from __future__ import annotations

import http.client
from collections.abc import Iterable

from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.http.http_targets import (
    HttpTarget as AuthTarget,
    build_url as build_url,
    choose_scheme as choose_scheme,
    http_target_from_port_event,
    http_target_from_text,
    http_targets,
    normalize_path as normalize_path,
    split_host_port as split_host_port,
)
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULTS = {"path": "/", "scheme": "auto", "method": "HEAD", "timeout": 5}

# Administrative/login path hints used for passive exposure findings.
#
# Used by: `is_adminish_path()`, which keeps the path classification data out
# of the finding-generation branches.
ADMIN_PATH_HINTS = ("/admin", "/login", "/manager", "/console", "/dashboard", "/wp-admin")


@commandlet(
    name="http_auth",
    description="Probe HTTP auth challenges and report passive auth posture findings.",
    usage="http_auth [options] [target ...]",
    examples=(
        "http_auth https://example.test/admin",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_auth path=/admin",
    ),
)
@option("path", "request path", "/")
@option("scheme", "scheme override", "auto", ("auto", "http", "https"))
@option("method", "HTTP method", "HEAD", ("HEAD", "GET"))
@option("timeout", "request timeout seconds", "5")
class HttpAuth(CommandletBase):
    """Probe one request and emit HTTP authentication posture facts.

    Called by: PluginRegistry/runner dispatch for the `http_auth` commandlet.

    Emits: plugin-owned `http.auth` facts and `finding.candidate` events for
    passive authentication posture observations.
    """

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Probe explicit URLs/hosts or HTTP-looking pipeline ports.

        Called by: the Bywaf runner through `CommandletBase.run()`.
        """
        parser = self.parser()
        # Add positional targets and runtime options to the argparse parser
        # that executes this commandlet invocation.
        parser.add_argument("targets", nargs="*")
        parser.add_argument("--path", default=self.var_default(context, "path", "/"))
        parser.add_argument("--scheme", choices=("auto", "http", "https"), default=self.var_default(context, "scheme", "auto"))
        parser.add_argument("--method", choices=("HEAD", "GET"), default=self.var_default(context, "method", "HEAD"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        # Parse command-line arguments into concrete runtime values.
        parsed = parser.parse_args(args)

        # Resolve direct or pipeline targets, then apply the global target
        # scope policy by comparing each AuthTarget by host.
        targets = filter_targets_by_host(
            context,
            auth_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
            lambda target: target.host,
        )
        for target in targets:
            # Record actual runtime use of the declared network capability.
            context.audit_capability("network.connect")

            # Send the configured method and normalize auth challenge headers.
            result = probe_auth(target, method=parsed.method, timeout=parsed.timeout)

            # Convert the probe result into the plugin-owned `http.auth`
            # event payload that the framework persists from yielded output.
            payload = result_payload(target, result, parsed.method)

            # Promote passive auth posture observations to finding candidates
            # before yielding the raw auth fact.
            for finding in auth_findings(payload):
                context.events.publish("finding.candidate", finding)
            yield payload

    def targets(self, targets, scheme, path, input_events):
        """Resolve target tuples for compatibility tests/callers.

        Called by: tests and older callers that expect tuple output rather
        than `AuthTarget` objects.
        """
        # Convert the shared HTTP target model back to the historical tuple
        # shape exposed by this commandlet helper.
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in auth_targets(list(targets or []), input_events, scheme, path)
        ]


def auth_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[AuthTarget]:
    """Resolve auth-probe targets from arguments or upstream port events.

    Called by: `HttpAuth.run()` and `HttpAuth.targets()`.
    """
    # Delegate URL/host/port parsing to the shared HTTP target helper so HTTP
    # plugins use consistent defaults and pipeline conversion.
    return http_targets(targets, input_events, scheme, path)


def target_from_port_event(event: Event, scheme: str, path: str) -> AuthTarget:
    """Convert one `port.open` event into an auth probe target.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_port_event(event, scheme, path)


def target_from_text(target: str, scheme: str, path: str) -> AuthTarget:
    """Parse URL, host, or host:port text into an AuthTarget.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_text(target, scheme, path)


def probe_auth(target: AuthTarget, *, method: str, timeout: float) -> dict[str, object]:
    """Perform one HTTP request and return auth challenge metadata.

    Called by: `HttpAuth.run()` once per scoped target.
    """
    # Pick the stdlib connection class that matches the resolved target scheme.
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection

    # Open an HTTP(S) connection to the target host and port.
    connection = connection_class(target.host, target.port, timeout=timeout)
    try:
        # Send the configured probe method to the target path.
        connection.request(method, target.path)

        # Read the server's HTTP response.
        response = connection.getresponse()

        # Get all response headers because auth challenges can appear multiple
        # times and can come from either origin or proxy authentication.
        challenges = response.getheaders()
        www_authenticate = [
            value
            for name, value in challenges
            if name.lower() == "www-authenticate" and value.strip()
        ]
        proxy_authenticate = [
            value
            for name, value in challenges
            if name.lower() == "proxy-authenticate" and value.strip()
        ]

        # Normalize challenge header values into scheme tokens and realm names.
        schemes = normalize_schemes(www_authenticate + proxy_authenticate)
        realms = challenge_realms(www_authenticate + proxy_authenticate)
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "www_authenticate": www_authenticate,
            "proxy_authenticate": proxy_authenticate,
            "schemes": schemes,
            "realms": realms,
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # Preserve a structured error payload so one failed target does not
        # abort the rest of the commandlet run.
        return {"ok": False, "error": str(exc), "schemes": [], "realms": []}
    finally:
        # Always release the socket-like connection object after probing.
        connection.close()


def normalize_schemes(challenges: list[str]) -> list[str]:
    """Return normalized authentication scheme tokens from challenge headers.

    Called by: `probe_auth()` after reading authentication challenge headers.
    """
    schemes = []
    for challenge in challenges:
        # The auth scheme is the leading token before challenge parameters.
        token = challenge.strip().split(None, 1)[0].strip(",")
        if token and token.replace("-", "").isalnum():
            schemes.append(token.upper())
    return sorted(set(schemes))


def challenge_realms(challenges: list[str]) -> list[str]:
    """Return realm values from simple WWW-Authenticate challenge headers.

    Called by: `probe_auth()` after reading authentication challenge headers.
    """
    realms = []
    for challenge in challenges:
        # This intentionally handles the common `realm="..."` form without
        # trying to implement a full HTTP auth parameter parser.
        lowered = challenge.lower()
        marker = 'realm="'
        start = lowered.find(marker)
        if start == -1:
            continue
        start += len(marker)
        end = challenge.find('"', start)
        if end != -1:
            realms.append(challenge[start:end])
    return sorted(set(realms))


def result_payload(target: AuthTarget, result: dict[str, object], method: str) -> dict[str, object]:
    """Return the plugin-owned `http.auth` fact payload.

    Called by: `HttpAuth.run()` before yielding the fact.
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

    Called by: `HttpAuth.run()` after one `http.auth` payload is built.
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


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return HttpAuth()
