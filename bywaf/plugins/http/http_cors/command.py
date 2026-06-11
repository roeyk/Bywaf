"""Command orchestration for HTTP CORS posture checks.

Provides argument parsing, target resolution, CORS probing, event payload
creation, and finding publication for the `http_cors` commandlet.

Consumes:
- `port.open` events or explicit URL/host command arguments.

Emits:
- `http.cors` for observed CORS response posture.
- `finding.candidate` for clear unsafe CORS policy observations.

Used by:
- HTTP CORS plugin registration: delegate commandlet execution.
- tests: verify Bywaf integration around pure detection and findings logic.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, CommandletBase
from bywaf.plugins.http.http_targets import (
    HttpTarget as CorsTarget,
    http_target_from_port_event,
    http_target_from_text,
    http_targets,
)
from bywaf.plugins.target_policy import filter_targets_by_host

from .detect import probe_cors
from .findings import cors_findings, result_payload

DEFAULTS = {
    "origin": "https://bywaf-origin-check.invalid",
    "path": "/",
    "request_method": "GET",
    "scheme": "auto",
    "timeout": 5,
}


def run_http_cors(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Run one HTTP CORS commandlet invocation.

    Called by: `HttpCors.run()`.

    Emits yielded `http.cors` payloads plus persisted `finding.candidate`
    events.
    """
    parser = commandlet.parser()
    # Add positional targets and runtime options to the argparse parser
    # that executes this commandlet invocation.
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--origin", default=commandlet.var_default(context, "origin", DEFAULTS["origin"]))
    parser.add_argument("--path", default=commandlet.var_default(context, "path", DEFAULTS["path"]))
    parser.add_argument(
        "--request-method",
        choices=("GET", "POST", "PUT", "DELETE", "PATCH"),
        default=commandlet.var_default(context, "request_method", DEFAULTS["request_method"]),
    )
    parser.add_argument("--scheme", choices=("auto", "http", "https"), default=commandlet.var_default(context, "scheme", DEFAULTS["scheme"]))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", DEFAULTS["timeout"], cast=float))
    # Parse command-line arguments into concrete runtime values.
    parsed = parser.parse_args(args)

    # Resolve direct or pipeline targets, then apply the global target scope
    # policy by comparing each CorsTarget by host.
    targets = filter_targets_by_host(
        context,
        cors_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
        lambda target: target.host,
    )
    for target in targets:
        # Record actual runtime use of the declared network capability.
        context.audit_capability("network.connect")

        # Send the CORS preflight-style OPTIONS request and normalize response
        # headers into a loose result dict.
        result = probe_cors(
            target,
            origin=parsed.origin,
            request_method=parsed.request_method,
            timeout=parsed.timeout,
        )

        # Convert the probe result into the plugin-owned `http.cors` event
        # payload that the framework persists from yielded output.
        payload = result_payload(target, result, parsed.origin, parsed.request_method)

        # Promote clear unsafe CORS policy observations to finding candidates
        # before yielding the raw CORS fact.
        for finding in cors_findings(payload):
            context.events.publish("finding.candidate", finding)
        yield payload


def cors_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[CorsTarget]:
    """Resolve CORS-probe targets from arguments or upstream port events.

    Called by: `run_http_cors()` and `HttpCors.targets()`.
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


__all__ = [
    "DEFAULTS",
    "CorsTarget",
    "cors_targets",
    "run_http_cors",
    "target_from_port_event",
    "target_from_text",
]
