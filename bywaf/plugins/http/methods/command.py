"""Command orchestration for HTTP method checks.

Provides argument parsing, target resolution, OPTIONS probing, event payload
creation, and finding publication for the `http_methods` commandlet.

Consumes:
- `port.open` events or explicit URL/host command arguments.

Emits:
- `http.methods` for observed Allow/Public method posture.
- `finding.candidate` for risky allowed method observations.

Used by:
- HTTP methods plugin registration: delegate commandlet execution.
- tests: verify Bywaf integration around pure detection and findings logic.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, CommandletBase, parse_bool
from bywaf.plugins.http.targets import (
    HttpTarget as MethodTarget,
    http_target_from_port,
    http_target_from_text,
    http_targets,
)
from bywaf.plugins.target_policy import filter_targets_by_host

from .detect import probe_methods
from .findings import method_findings, methods_from_payload, result_payload

DEFAULTS = {"path": "/", "scheme": "auto", "silent": "false", "timeout": 5}


def run_http_methods(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Run one HTTP methods commandlet invocation.

    Called by: `HttpMethods.run()`.

    Emits yielded `http.methods` payloads plus persisted `finding.candidate`
    events.
    """
    parser = commandlet.parser()
    # Add positional targets and runtime options to the argparse parser
    # that executes this commandlet invocation.
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--path", default=commandlet.var_default(context, "path", DEFAULTS["path"]))
    parser.add_argument("--scheme", choices=("auto", "http", "https"), default=commandlet.var_default(context, "scheme", DEFAULTS["scheme"]))
    parser.add_argument("-s", "--silent", action="store_true", default=commandlet.var_default(context, "silent", False, cast=parse_bool))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", DEFAULTS["timeout"], cast=float))
    # Parse command-line arguments into concrete runtime values.
    parsed = parser.parse_args(args)

    # Resolve direct or pipeline targets, then apply the global target scope
    # policy by comparing each MethodTarget by host.
    targets = filter_targets_by_host(
        context,
        method_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
        lambda target: target.host,
    )
    for target in targets:
        # Record actual runtime use of the declared network capability.
        context.audit_capability("network.connect")

        # Send OPTIONS and normalize the response into a loose result dict.
        result = probe_methods(target, timeout=parsed.timeout)

        # Convert the probe result into the plugin-owned `http.methods` event
        # payload that the framework persists from yielded output.
        payload = result_payload(target, result)

        # Promote risky method combinations to finding candidates before
        # yielding the method fact.
        for finding in method_findings(payload):
            context.events.publish("finding.candidate", finding)
        methods = methods_from_payload(payload)

        # Request compact operator feedback for interactive runs. The
        # structured event and finding candidates remain the primary data.
        context.alert(
            f"observed HTTP methods {target.url} methods={','.join(methods) or 'unknown'}",
            silent=parsed.silent,
        )
        yield payload


def method_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[MethodTarget]:
    """Resolve method-probe targets from arguments or upstream port events.

    Called by: `run_http_methods()` and `HttpMethods.targets()`.
    """
    # Delegate URL/host/port parsing to the shared HTTP target helper so HTTP
    # plugins use consistent defaults and pipeline conversion.
    return http_targets(targets, input_events, scheme, path)


def target_from_port_event(event: Event, scheme: str, path: str) -> MethodTarget:
    """Convert one `port.open` event into a method probe target.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_port(event, scheme, path)


def target_from_text(target: str, scheme: str, path: str) -> MethodTarget:
    """Parse URL, host, or host:port text into a MethodTarget.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_text(target, scheme, path)


__all__ = [
    "DEFAULTS",
    "MethodTarget",
    "method_targets",
    "run_http_methods",
    "target_from_port_event",
    "target_from_text",
]
