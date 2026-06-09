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
    """Probe one request with an Origin header and emit CORS posture facts."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Probe explicit URLs/hosts or HTTP-looking pipeline ports."""
        parser = self.parser()
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
        parsed = parser.parse_args(args)
        targets = filter_targets_by_host(
            context,
            cors_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
            lambda target: target.host,
        )
        for target in targets:
            context.audit_capability("network.connect")
            result = probe_cors(
                target,
                origin=parsed.origin,
                request_method=parsed.request_method,
                timeout=parsed.timeout,
            )
            payload = result_payload(target, result, parsed.origin, parsed.request_method)
            for finding in cors_findings(payload):
                context.events.publish("finding.candidate", finding)
            yield payload

    def targets(self, targets, scheme, path, input_events):
        """Resolve explicit targets or derive targets from `port.open` events."""
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
    """Resolve CORS-probe targets from arguments or upstream port events."""
    return http_targets(targets, input_events, scheme, path)


def target_from_port_event(event: Event, scheme: str, path: str) -> CorsTarget:
    """Convert one `port.open` event into a CORS probe target."""
    return http_target_from_port_event(event, scheme, path)


def target_from_text(target: str, scheme: str, path: str) -> CorsTarget:
    """Parse URL, host, or host:port text into a CorsTarget."""
    return http_target_from_text(target, scheme, path)


def probe_cors(
    target: CorsTarget,
    *,
    origin: str,
    request_method: str,
    timeout: float,
) -> dict[str, object]:
    """Perform one CORS preflight-style request and return response metadata."""
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(target.host, target.port, timeout=timeout)
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": request_method,
    }
    try:
        connection.request("OPTIONS", target.path, headers=headers)
        response = connection.getresponse()
        allow_origin = response.getheader("Access-Control-Allow-Origin") or ""
        allow_credentials = response.getheader("Access-Control-Allow-Credentials") or ""
        allow_methods = response.getheader("Access-Control-Allow-Methods") or ""
        vary = response.getheader("Vary") or ""
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
        return {"ok": False, "error": str(exc)}
    finally:
        connection.close()


def same_origin_value(value: str, origin: str) -> bool:
    """Return whether a response origin exactly matches the request origin."""
    return value.strip().casefold() == origin.strip().casefold()


def truthy_header(value: str) -> bool:
    """Return whether a response header means true."""
    return value.strip().casefold() == "true"


def result_payload(
    target: CorsTarget,
    result: dict[str, object],
    origin: str,
    request_method: str,
) -> dict[str, object]:
    """Return the plugin-owned `http.cors` fact payload."""
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
    """Promote clear unsafe CORS posture into normalized finding candidates."""
    findings: list[dict[str, object]] = []
    if payload.get("reflected_origin") and payload.get("credentials_allowed"):
        findings.append(cors_finding(payload, "web.cors.arbitrary_origin_with_credentials", "CORS reflects arbitrary Origin with credentials", "high"))
    elif payload.get("reflected_origin"):
        findings.append(cors_finding(payload, "web.cors.arbitrary_origin_reflected", "CORS reflects arbitrary Origin", "medium"))
    if payload.get("wildcard_origin") and payload.get("credentials_allowed"):
        findings.append(cors_finding(payload, "web.cors.wildcard_with_credentials", "CORS wildcard origin allows credentials", "medium"))
    return findings


def cors_finding(
    payload: dict[str, object],
    finding_class: str,
    title: str,
    severity: str,
) -> dict[str, object]:
    """Return one normalized CORS finding candidate."""
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
    """Return normalized target details for finding candidates."""
    return {
        "scheme": str(payload["scheme"]),
        "host": str(payload["host"]),
        "port": str(payload["port"]),
        "path": str(payload["path"]),
    }


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HttpCors()
