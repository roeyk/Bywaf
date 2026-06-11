"""HTTP CORS posture commandlet."""

from __future__ import annotations

import http.client
from collections.abc import Iterable

from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.http.http_targets import (
    HttpTarget as CorsTarget,
    build_url as build_url,
    choose_scheme as choose_scheme,
    http_target_from_port_event,
    http_target_from_text,
    http_targets,
    normalize_path as normalize_path,
    split_host_port as split_host_port,
)
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULTS = {
    "origin": "https://bywaf-origin-check.invalid",
    "path": "/",
    "request_method": "GET",
    "scheme": "auto",
    "timeout": 5,
}


@commandlet(
    name="http_cors",
    description="Probe HTTP CORS posture and report unsafe cross-origin policy candidates.",
    usage="http_cors [options] [target ...]",
    examples=(
        "http_cors https://example.test/api",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_cors path=/api",
    ),
)
@option("origin", "Origin header value", DEFAULTS["origin"])
@option("path", "request path", DEFAULTS["path"])
@option("request-method", "CORS requested method", DEFAULTS["request_method"], ("GET", "POST", "PUT", "DELETE", "PATCH"))
@option("scheme", "scheme override", DEFAULTS["scheme"], ("auto", "http", "https"))
@option("timeout", "request timeout seconds", "5")
class HttpCors(CommandletBase):
    """Probe one request with an Origin header and emit CORS posture facts.

    Called by: PluginRegistry/runner dispatch for the `http_cors` commandlet.

    Emits: plugin-owned `http.cors` facts and `finding.candidate` events for
    clear unsafe CORS posture.
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
        parser.add_argument("--origin", default=self.var_default(context, "origin", DEFAULTS["origin"]))
        parser.add_argument("--path", default=self.var_default(context, "path", DEFAULTS["path"]))
        parser.add_argument(
            "--request-method",
            choices=("GET", "POST", "PUT", "DELETE", "PATCH"),
            default=self.var_default(context, "request_method", DEFAULTS["request_method"]),
        )
        parser.add_argument("--scheme", choices=("auto", "http", "https"), default=self.var_default(context, "scheme", DEFAULTS["scheme"]))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", DEFAULTS["timeout"], cast=float))
        # Parse command-line arguments into concrete runtime values.
        parsed = parser.parse_args(args)

        # Resolve direct or pipeline targets, then apply the global target
        # scope policy by comparing each CorsTarget by host.
        targets = filter_targets_by_host(
            context,
            cors_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
            lambda target: target.host,
        )
        for target in targets:
            # Record actual runtime use of the declared network capability.
            context.audit_capability("network.connect")

            # Send the CORS preflight-style OPTIONS request and normalize
            # response headers into a loose result dict.
            result = probe_cors(
                target,
                origin=parsed.origin,
                request_method=parsed.request_method,
                timeout=parsed.timeout,
            )

            # Convert the probe result into the plugin-owned `http.cors`
            # event payload that the framework persists from yielded output.
            payload = result_payload(target, result, parsed.origin, parsed.request_method)

            # Promote clear unsafe CORS policy observations to finding
            # candidates before yielding the raw CORS fact.
            for finding in cors_findings(payload):
                context.events.publish("finding.candidate", finding)
            yield payload

    def targets(self, targets, scheme, path, input_events):
        """Resolve target tuples for compatibility tests/callers.

        Called by: tests and older callers that expect tuple output rather
        than `CorsTarget` objects.
        """
        # Convert the shared HTTP target model back to the historical tuple
        # shape exposed by this commandlet helper.
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in cors_targets(list(targets or []), input_events, scheme, path)
        ]


def cors_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[CorsTarget]:
    """Resolve CORS-probe targets from arguments or upstream port events.

    Called by: `HttpCors.run()` and `HttpCors.targets()`.
    """
    # Delegate URL/host/port parsing to the shared HTTP target helper so HTTP
    # plugins use consistent defaults and pipeline conversion.
    return http_targets(targets, input_events, scheme, path)


def target_from_port_event(event: Event, scheme: str, path: str) -> CorsTarget:
    """Convert one `port.open` event into a CORS probe target.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_port_event(event, scheme, path)


def target_from_text(target: str, scheme: str, path: str) -> CorsTarget:
    """Parse URL, host, or host:port text into a CorsTarget.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_text(target, scheme, path)


def probe_cors(
    target: CorsTarget,
    *,
    origin: str,
    request_method: str,
    timeout: float,
) -> dict[str, object]:
    """Perform one CORS preflight-style request and return response metadata.

    Called by: `HttpCors.run()` once per scoped target.
    """
    # Pick the stdlib connection class that matches the resolved target scheme.
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection

    # Open an HTTP(S) connection to the target host and port.
    connection = connection_class(target.host, target.port, timeout=timeout)

    # Build the CORS request headers that simulate a browser cross-origin
    # preflight check for the requested method.
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": request_method,
    }
    try:
        # Send the OPTIONS request with the Origin and requested-method headers.
        connection.request("OPTIONS", target.path, headers=headers)

        # Read the server's CORS preflight response.
        response = connection.getresponse()

        # Extract the CORS posture headers this commandlet evaluates.
        allow_origin = response.getheader("Access-Control-Allow-Origin") or ""
        allow_credentials = response.getheader("Access-Control-Allow-Credentials") or ""
        allow_methods = response.getheader("Access-Control-Allow-Methods") or ""
        vary = response.getheader("Vary") or ""

        # Return both raw header values and normalized booleans for finding
        # generation and display/reporting.
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "allow_methods": allow_methods,
            "vary": vary,
            "reflected_origin": same_origin_value(allow_origin, origin),
            "wildcard_origin": allow_origin.strip() == "*",
            "credentials_allowed": truthy_header(allow_credentials),
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # Preserve a structured error payload so one failed target does not
        # abort the rest of the commandlet run.
        return {"ok": False, "error": str(exc)}
    finally:
        # Always release the socket-like connection object after probing.
        connection.close()


def same_origin_value(value: str, origin: str) -> bool:
    """Return whether a response origin exactly matches the request origin.

    Called by: `probe_cors()` when deriving `reflected_origin`.
    """
    # Compare stripped, casefolded values; CORS origin matching is exact for
    # this passive check.
    return value.strip().casefold() == origin.strip().casefold()


def truthy_header(value: str) -> bool:
    """Return whether a response header means true.

    Called by: `probe_cors()` for Access-Control-Allow-Credentials.
    """
    # The CORS credentials header is only enabled by the literal true value.
    return value.strip().casefold() == "true"


def result_payload(
    target: CorsTarget,
    result: dict[str, object],
    origin: str,
    request_method: str,
) -> dict[str, object]:
    """Return the plugin-owned `http.cors` fact payload.

    Called by: `HttpCors.run()` before yielding the fact.
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

    Called by: `HttpCors.run()` after one `http.cors` payload is built.
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


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return HttpCors()
