"""Command orchestration for HTTP authentication checks.

Provides argument parsing, target resolution, authentication probing, event
payload creation, and finding publication for the `http_auth` commandlet.

Consumes:
- `port.open` events or explicit URL/host command arguments.

Emits:
- `http.auth` for observed authentication challenge posture.
- `finding.candidate` for passive authentication posture observations.

Used by:
- HTTP auth plugin registration: delegate commandlet execution.
- tests: verify Bywaf integration around pure detection and findings logic.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, CommandletBase
from bywaf.plugins.http.http_targets import (
    HttpTarget as AuthTarget,
    http_target_from_port_event,
    http_target_from_text,
    http_targets,
)
from bywaf.plugins.target_policy import filter_targets_by_host

from .detect import probe_auth
from .findings import auth_findings, result_payload

DEFAULTS = {"path": "/", "scheme": "auto", "method": "HEAD", "timeout": 5}


def run_http_auth(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Run one HTTP auth commandlet invocation.

    Called by: `HttpAuth.run()`.

    Emits yielded `http.auth` payloads plus persisted `finding.candidate`
    events.
    """
    parser = commandlet.parser()
    # Add positional targets and runtime options to the argparse parser that
    # executes this commandlet invocation.
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--path", default=commandlet.var_default(context, "path", DEFAULTS["path"]))
    parser.add_argument("--scheme", choices=("auto", "http", "https"), default=commandlet.var_default(context, "scheme", DEFAULTS["scheme"]))
    parser.add_argument("--method", choices=("HEAD", "GET"), default=commandlet.var_default(context, "method", DEFAULTS["method"]))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", DEFAULTS["timeout"], cast=float))
    # Parse command-line arguments into concrete runtime values.
    parsed = parser.parse_args(args)

    # Resolve direct or pipeline targets, then apply the global target scope
    # policy by comparing each AuthTarget by host.
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

        # Convert the probe result into the plugin-owned `http.auth` event
        # payload that the framework persists from yielded output.
        payload = result_payload(target, result, parsed.method)

        # Promote passive auth posture observations to finding candidates
        # before yielding the raw auth fact.
        for finding in auth_findings(payload):
            context.events.publish("finding.candidate", finding)
        yield payload


def auth_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[AuthTarget]:
    """Resolve auth-probe targets from arguments or upstream port events.

    Called by: `run_http_auth()` and `HttpAuth.targets()`.
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


__all__ = [
    "AuthTarget",
    "DEFAULTS",
    "auth_targets",
    "run_http_auth",
    "target_from_port_event",
    "target_from_text",
]
